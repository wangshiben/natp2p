package router

import (
	"context"
	"testing"

	"bnfs_p2p/p2pnode"
)

func TestRouteTree_StaticRoute(t *testing.T) {
	tree := newRouteTree()
	called := false
	handler := func(ctx context.Context, msg *p2pnode.Message, conn RouterConnection) {
		called = true
	}

	err := tree.insert("/user/profile", handler)
	if err != nil {
		t.Fatalf("insert failed: %v", err)
	}

	h, params := tree.search("/user/profile")
	if h == nil {
		t.Fatal("handler not found")
	}
	if len(params) != 0 {
		t.Errorf("expected no params, got %v", params)
	}

	h(nil, nil, nil)
	if !called {
		t.Error("handler not called")
	}
}

func TestRouteTree_ParamRoute(t *testing.T) {
	tree := newRouteTree()
	handler := func(ctx context.Context, msg *p2pnode.Message, conn RouterConnection) {}

	err := tree.insert("/user/:id/profile", handler)
	if err != nil {
		t.Fatalf("insert failed: %v", err)
	}

	h, params := tree.search("/user/123/profile")
	if h == nil {
		t.Fatal("handler not found")
	}
	if params["id"] != "123" {
		t.Errorf("expected id=123, got %v", params)
	}
}

func TestRouteTree_WildcardRoute(t *testing.T) {
	tree := newRouteTree()
	handler := func(ctx context.Context, msg *p2pnode.Message, conn RouterConnection) {}

	err := tree.insert("/files/*path", handler)
	if err != nil {
		t.Fatalf("insert failed: %v", err)
	}

	h, params := tree.search("/files/a/b/c.txt")
	if h == nil {
		t.Fatal("handler not found")
	}
	if params["path"] != "a/b/c.txt" {
		t.Errorf("expected path=a/b/c.txt, got %v", params)
	}
}

func TestRouteTree_Priority(t *testing.T) {
	tree := newRouteTree()
	staticCalled := false
	paramCalled := false

	staticHandler := func(ctx context.Context, msg *p2pnode.Message, conn RouterConnection) {
		staticCalled = true
	}
	paramHandler := func(ctx context.Context, msg *p2pnode.Message, conn RouterConnection) {
		paramCalled = true
	}

	tree.insert("/user/admin", staticHandler)
	tree.insert("/user/:id", paramHandler)

	// 访问静态路由应匹配静态 handler
	h, _ := tree.search("/user/admin")
	if h == nil {
		t.Fatal("handler not found")
	}
	h(nil, nil, nil)
	if !staticCalled || paramCalled {
		t.Error("static route should take priority")
	}

	// 重置
	staticCalled = false
	paramCalled = false

	// 访问动态路由应匹配参数 handler
	h, params := tree.search("/user/123")
	if h == nil {
		t.Fatal("handler not found")
	}
	h(nil, nil, nil)
	if staticCalled || !paramCalled {
		t.Error("param route should match")
	}
	if params["id"] != "123" {
		t.Errorf("expected id=123, got %v", params)
	}
}

func TestRouteTree_ParamConflict(t *testing.T) {
	tree := newRouteTree()
	handler := func(ctx context.Context, msg *p2pnode.Message, conn RouterConnection) {}

	tree.insert("/user/:id", handler)
	err := tree.insert("/user/:name", handler)
	if err == nil {
		t.Error("expected conflict error for different param names")
	}
}

func TestRouteTree_WildcardMustBeLast(t *testing.T) {
	tree := newRouteTree()
	handler := func(ctx context.Context, msg *p2pnode.Message, conn RouterConnection) {}

	err := tree.insert("/files/*path/extra", handler)
	if err == nil {
		t.Error("expected error for wildcard not at end")
	}
}

func TestRouteTree_DuplicateRoute(t *testing.T) {
	tree := newRouteTree()
	handler := func(ctx context.Context, msg *p2pnode.Message, conn RouterConnection) {}

	tree.insert("/user/profile", handler)
	err := tree.insert("/user/profile", handler)
	if err == nil {
		t.Error("expected error for duplicate route")
	}
}

func TestRouteTree_NotFound(t *testing.T) {
	tree := newRouteTree()
	handler := func(ctx context.Context, msg *p2pnode.Message, conn RouterConnection) {}

	tree.insert("/user/profile", handler)

	h, _ := tree.search("/user/settings")
	if h != nil {
		t.Error("expected no match")
	}
}

func TestRouteTree_RootRoute(t *testing.T) {
	tree := newRouteTree()
	called := false
	handler := func(ctx context.Context, msg *p2pnode.Message, conn RouterConnection) {
		called = true
	}

	tree.insert("/", handler)

	h, _ := tree.search("/")
	if h == nil {
		t.Fatal("root handler not found")
	}
	h(nil, nil, nil)
	if !called {
		t.Error("root handler not called")
	}
}

func TestRouteTree_MultipleParams(t *testing.T) {
	tree := newRouteTree()
	handler := func(ctx context.Context, msg *p2pnode.Message, conn RouterConnection) {}

	tree.insert("/user/:uid/post/:pid", handler)

	h, params := tree.search("/user/123/post/456")
	if h == nil {
		t.Fatal("handler not found")
	}
	if params["uid"] != "123" {
		t.Errorf("expected uid=123, got %v", params)
	}
	if params["pid"] != "456" {
		t.Errorf("expected pid=456, got %v", params)
	}
}

func TestSplitPath(t *testing.T) {
	tests := []struct {
		input    string
		expected []string
	}{
		{"/user/profile", []string{"user", "profile"}},
		{"/user//profile/", []string{"user", "profile"}},
		{"user/profile", []string{"user", "profile"}},
		{"/", []string{}},
		{"", []string{}},
	}

	for _, tt := range tests {
		result := splitPath(tt.input)
		if len(result) != len(tt.expected) {
			t.Errorf("splitPath(%q) = %v, want %v", tt.input, result, tt.expected)
			continue
		}
		for i := range result {
			if result[i] != tt.expected[i] {
				t.Errorf("splitPath(%q)[%d] = %q, want %q", tt.input, i, result[i], tt.expected[i])
			}
		}
	}
}
