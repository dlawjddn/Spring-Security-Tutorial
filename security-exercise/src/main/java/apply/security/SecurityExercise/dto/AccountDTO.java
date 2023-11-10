package apply.security.SecurityExercise.dto;

import apply.security.SecurityExercise.domain.Account;
import lombok.Data;

@Data
public class AccountDTO {
    private String username;
    private String password;
    private String age;
    private String role;
    public Account toAccount(){
        return new Account(this.username, this.password, this.age, this.role);
    }
}
