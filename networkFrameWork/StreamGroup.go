package networkFrameWork

import (
	"bnfs_p2p/network"
	"context"
	"errors"
	"sync"
)

// StreamGroup 负责管理多个Stream
type StreamGroup struct {
	// 负责处理node的连接等信息
	relayStream          network.Stream
	connectionMap        map[string]*connectionResource // 此Stream目前保持会话的所有clientStream
	beforeConnectionHook BeforeStreamOnHook
	lock                 sync.Mutex
	cancelFunc           context.CancelFunc
	ctx                  context.Context
	nodeId               string
}

type connectionResource struct {
	stream network.Stream
	flag   context.CancelFunc
}

func (c *connectionResource) Close() {
	c.flag()
	c.stream.Close()
}
func (c *connectionResource) ListenStream() (*network.Message, error) {
	message, err := c.stream.NextMessage()
	if err != nil {
		return nil, err
	}
	return message, nil
}
func defaultHookfunc(ClientStream, ServerStream network.Stream, FirstMessage *network.Message) error {
	return nil
}

// BeforeStreamOnHook 预留给SSL套件
type BeforeStreamOnHook func(ClientStream, ServerStream network.Stream, FirstMessage *network.Message) error

// StreamOn 当有一个新Stream要建立连接时，调用，注意: 此时建立连接的Stream是必须携带connectionId的,一般第一条消息无Payload
func (s *StreamGroup) StreamOn(stream network.Stream, FirstMessage *network.Message) error {
	s.lock.Lock()
	connectionId := FirstMessage.Header.ConnectionId
	ctx, cancelFunc := context.WithCancel(context.Background())
	c := &connectionResource{
		stream: stream,
		flag:   cancelFunc,
	}
	if len(connectionId) == 0 {
		return errors.New("connectionId is empty")
	}
	s.connectionMap[connectionId] = c
	s.lock.Unlock()

	err := s.beforeConnectionHook(stream, s.relayStream, FirstMessage)
	if err != nil {
		s.CloseTargetConnection(connectionId)
	}
	go func(c *connectionResource, connectionId string, ctx context.Context) {
		for {
			select {
			case <-ctx.Done():
				return
			default:
				message, err := c.ListenStream()

				if err != nil {
					s.CloseTargetConnection(connectionId)
					return
				}
				err = s.relayStream.SendMessage(ctx, message)
				if err != nil {
					s.CloseTargetConnection(connectionId)
				}
			}

		}
	}(c, FirstMessage.Header.ConnectionId, ctx)
	return err
}

func (s *StreamGroup) StartListen() {
	for {
		select {
		case <-s.ctx.Done():
			return
		default:
			message, err := s.relayStream.NextMessage()
			if err != nil {

				return
			}

			resource := s.connectionMap[message.Header.ConnectionId]
			if resource == nil {
				// 目前策略是忽略本次连接
				// TODO: 消息转发
				continue
			}
			resource.stream.SendMessage(s.ctx, message)
		}

	}
}

func NewStreamGroup(relayStream network.Stream, beforeConnectionHook BeforeStreamOnHook) *StreamGroup {
	ctx, cancelFunc := context.WithCancel(context.Background())
	return &StreamGroup{
		relayStream:          relayStream,
		connectionMap:        make(map[string]*connectionResource),
		beforeConnectionHook: beforeConnectionHook,
		ctx:                  ctx,
		cancelFunc:           cancelFunc,
	}
}

func (s *StreamGroup) CloseTargetConnection(connectionId string) error {

	s.lock.Lock()
	defer s.lock.Unlock()
	c := s.connectionMap[connectionId]
	if c == nil {
		return errors.New("connectionId not exist or it's already closed")
	}
	delete(s.connectionMap, connectionId)
	c.Close()
	return nil
}
