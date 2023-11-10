package apply.security.SecurityExercise.controller.user;

import apply.security.SecurityExercise.dto.AccountDTO;
import apply.security.SecurityExercise.service.AccountService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;

@Controller
@RequiredArgsConstructor
public class UserController {
    private final AccountService accountService;
    @GetMapping("/mypage")
    public String myPage() throws Exception {
        return "user/mypage";
    }
    @GetMapping("/users")
    public String createUser(){
        return "user/login/register";
    }
    @PostMapping("/users")
    public String createUser(AccountDTO accountDTO){
        accountService.createAccount(accountDTO);
        return "redirect:/";
    }
}
