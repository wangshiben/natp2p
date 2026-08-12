package main

import "testing"

// TestLedger_CreditDebitAllow 验证账本充值/扣减/放行裁决逻辑。
func TestLedger_CreditDebitAllow(t *testing.T) {
	l := newLedger("")
	node := "node-x"

	// 充值 1000B。
	if bal := l.credit(node, 1000); bal != 1000 {
		t.Fatalf("充值后余额应为 1000, 实际 %d", bal)
	}
	// 扣减 400B → 余额 600 > 0 → 放行。
	if bal := l.debit(node, 400); bal != 600 {
		t.Fatalf("扣减 400 后余额应为 600, 实际 %d", bal)
	}
	// 再扣 700B → 余额 -100 < 0 → 应熔断（Allow=false 由 handler 据 bal>0 判定）。
	if bal := l.debit(node, 700); bal != -100 {
		t.Fatalf("超额扣减后余额应为 -100, 实际 %d", bal)
	}
	if l.balance(node) > 0 {
		t.Fatalf("余额已透支, 不应 >0")
	}
	// 未知节点余额为 0。
	if bal := l.balance("unknown"); bal != 0 {
		t.Fatalf("未知节点余额应为 0, 实际 %d", bal)
	}
}

// TestLedger_ReserveAtomicDualDebit 验证连接保证金原子双扣：
// 双方余额都够才一起扣、返回 allow；任一方不足则都不扣、返回拒绝。
func TestLedger_ReserveAtomicDualDebit(t *testing.T) {
	l := newLedger("")
	cli, srv := "client", "server"
	const cFee, sFee = 5 << 20, 50 << 10 // 5MB / 0.05MB

	// 都不足：都不扣，拒绝。
	if allow, _, _ := l.reserve(cli, cFee, srv, sFee); allow {
		t.Fatal("双方 0 余额应拒绝")
	}
	l.credit(cli, 12<<20) // client 12MB
	l.credit(srv, 1<<20)  // server 1MB

	// 都够：一起扣，放行。
	allow, cBal, sBal := l.reserve(cli, cFee, srv, sFee)
	if !allow || cBal != 12<<20-cFee || sBal != 1<<20-sFee {
		t.Fatalf("应放行并各扣一笔: allow=%v cBal=%d sBal=%d", allow, cBal, sBal)
	}

	// 掏空 server 到不足一笔入场费：此时即便 client 够也必须拒绝，且都不扣。
	l.debit(srv, l.balance(srv)-(sFee-1)) // 令 server 余额 = sFee-1
	cBefore, sBefore := l.balance(cli), l.balance(srv)
	if allow, _, _ := l.reserve(cli, cFee, srv, sFee); allow {
		t.Fatal("server 不足应拒绝")
	}
	if l.balance(cli) != cBefore || l.balance(srv) != sBefore {
		t.Fatal("被拒时任一方都不应被扣（原子性）")
	}
}

// TestLedger_Persistence 验证账本落盘后可重新加载。
func TestLedger_Persistence(t *testing.T) {
	path := t.TempDir() + "/ledger.json"
	l1 := newLedger(path)
	l1.credit("n1", 777)
	l1.credit("n2", 42)

	l2 := newLedger(path) // 重新加载
	if l2.balance("n1") != 777 || l2.balance("n2") != 42 {
		t.Fatalf("重载后余额不符: n1=%d n2=%d", l2.balance("n1"), l2.balance("n2"))
	}
}
