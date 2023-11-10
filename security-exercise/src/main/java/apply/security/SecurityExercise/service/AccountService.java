package apply.security.SecurityExercise.service;

import apply.security.SecurityExercise.domain.Account;
import apply.security.SecurityExercise.dto.AccountDTO;
import apply.security.SecurityExercise.repository.AccountRepository;
import lombok.Builder;
import lombok.RequiredArgsConstructor;
import org.modelmapper.ModelMapper;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.ui.ModelMap;

@Service
@RequiredArgsConstructor
public class AccountService {
    private final AccountRepository accountRepository;
    private final PasswordEncoder passwordEncoder;
    @Transactional
    public void createAccount(AccountDTO accountDTO){
        Account createdAccount = accountDTO.toAccount();
        createdAccount.encryptionPassword(passwordEncoder.encode(createdAccount.getPassword()));
        accountRepository.save(createdAccount);
    }
    public Account findByUsername(String username){
        return accountRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("Not Found"));
    }

}
