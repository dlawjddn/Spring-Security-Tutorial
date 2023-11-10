package apply.security.SecurityExercise.domain;

import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import lombok.Getter;
import lombok.NoArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;

@Entity
@NoArgsConstructor
@Getter
public class Account {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    private String username;
    private String password;
    private String age;
    private String role;

    public Account(String username, String password, String age, String role) {
        this.username = username;
        this.password = password;
        this.age = age;
        this.role = role;
    }
    public void encryptionPassword(String encodedPassword){
        this.password = encodedPassword;
    }
}
