package com.pipejack.banking.service;

import com.pipejack.banking.model.Account;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicLong;

@Service
public class AccountService {
    private final List<Account> accounts = new ArrayList<>();
    private final AtomicLong counter = new AtomicLong(1);

    public AccountService() {
        accounts.add(new Account(counter.getAndIncrement(), "Alice", 10000.0));
        accounts.add(new Account(counter.getAndIncrement(), "Bob", 5000.0));
        accounts.add(new Account(counter.getAndIncrement(), "Charlie", 7500.0));
    }

    public List<Account> getAllAccounts() {
        return accounts;
    }

    public Account getAccount(Long id) {
        return accounts.stream().filter(a -> a.getId().equals(id)).findFirst().orElse(null);
    }

    public Account createAccount(String holderName, double initialBalance) {
        Account account = new Account(counter.getAndIncrement(), holderName, initialBalance);
        accounts.add(account);
        return account;
    }

    public String transfer(Long fromId, Long toId, double amount) {
        Account from = getAccount(fromId);
        Account to = getAccount(toId);
        if (from == null || to == null) return "Invalid account";
        if (from.getBalance() < amount) return "Insufficient funds";
        from.setBalance(from.getBalance() - amount);
        to.setBalance(to.getBalance() + amount);
        return "Transfer successful";
    }
}
