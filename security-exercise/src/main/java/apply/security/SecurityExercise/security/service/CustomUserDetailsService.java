package apply.security.SecurityExercise.security.service;

import apply.security.SecurityExercise.domain.Account;
import apply.security.SecurityExercise.repository.AccountRepository;
import apply.security.SecurityExercise.service.AccountService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.Optional;

@Service
@RequiredArgsConstructor
public class CustomUserDetailsService implements UserDetailsService {
    private final AccountRepository accountRepository;
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        Optional<Account> tempAccount = accountRepository.findByUsername(username);
        if (tempAccount.isEmpty()) throw new UsernameNotFoundException("username not found");
        Account findAccount = tempAccount.get();
        ArrayList<GrantedAuthority> authorities = new ArrayList<>();
        authorities.add(new SimpleGrantedAuthority(findAccount.getRole()));
        return new AccountContext(findAccount, authorities);
    }
}
