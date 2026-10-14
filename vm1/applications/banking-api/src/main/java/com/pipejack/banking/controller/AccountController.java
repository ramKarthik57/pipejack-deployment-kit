package com.pipejack.banking.controller;

import com.pipejack.banking.model.Account;
import com.pipejack.banking.service.AccountService;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/accounts")
public class AccountController {

    private final AccountService accountService;

    public AccountController(AccountService accountService) {
        this.accountService = accountService;
    }

    @GetMapping
    public List<Account> getAllAccounts() {
        return accountService.getAllAccounts();
    }

    @GetMapping("/{id}")
    public Account getAccount(@PathVariable Long id) {
        return accountService.getAccount(id);
    }

    @PostMapping
    public Account createAccount(@RequestParam String holderName,
                                 @RequestParam double initialBalance) {
        return accountService.createAccount(holderName, initialBalance);
    }

    @PostMapping("/transfer")
    public String transfer(@RequestParam Long fromId,
                           @RequestParam Long toId,
                           @RequestParam double amount) {
        return accountService.transfer(fromId, toId, amount);
    }
}
