package expertostech.autenticacao.jwt.data;

import expertostech.autenticacao.jwt.model.UsuarioModel;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Optional;

public class DetalheUsuarioData  implements UserDetails {

    //Para receber o usuário(Como foi declarado com o final tem que colocar no construtor)
    private final Optional<UsuarioModel> usuario;

    public DetalheUsuarioData(Optional<UsuarioModel> usuario){
        this.usuario = usuario;
    }


    /*O getAuthorities é referente as permissões do usuário*/
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        //Como as permissões do usuário não foi definida iremos retornar uma lista vazia
        return new ArrayList<>();
    }

    @Override
    public String getPassword() {
        /*O orElse informa se for vazio retorna alguma coisa*/
        return usuario.orElse(new UsuarioModel()).getPassword();
    }

    @Override
    public String getUsername() {
        return usuario.orElse(new UsuarioModel()).getLogin();
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }
}
