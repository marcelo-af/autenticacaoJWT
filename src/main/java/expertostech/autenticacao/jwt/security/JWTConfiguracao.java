package expertostech.autenticacao.jwt.security;

import expertostech.autenticacao.jwt.service.DetalheUsuarioServiceImpl;
import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

@EnableWebSecurity
public class JWTConfiguracao extends WebSecurityConfigurerAdapter {

    /*Na classe principal(AutenticacaoJwtApplication) colocamos para excluir a classe
    * SecurityAutoConfiguration(@SpringBootApplication(exclude = {SecurityAutoConfiguration.class})),
    * pois essa classe faz parte do WebSecurityConfigurerAdapter, depois tem que voltar na classe
    * principal e tirar essa exclusao */

    //Realiza a busca do usuario
    private final DetalheUsuarioServiceImpl usuarioService;

    private final PasswordEncoder passwordEncoder;

    public JWTConfiguracao(DetalheUsuarioServiceImpl usuarioService, PasswordEncoder passwordEncoder) {
        this.usuarioService = usuarioService;
        this.passwordEncoder = passwordEncoder;
    }

    /*Utiliza o usuarioService e o PasswordEncoder para validar a senha*/

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(usuarioService).passwordEncoder(passwordEncoder);
    }

    /*Configura como o springSecurity deve entender a página.
    * O csrf -> resolve ataques na aplicação aqui esta desabilitado,
    *  pq esta no ambiente de desenvolvimento e é para teste.
    * .antMatchers -> Toda vez que utiliza o springSecurity na pagina inical é solicitado
    * o login e senha por isso na configuração esta permiteAll para não solicitar Login e senha
    * na prorpia página do spring /login.
    * .anyRequest().authenticated() -> isso quer dizer que para outra solicitação deve estar autenticado
    * .addFilter -> É para validar a autenticação e validação
    * O .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS) ->
    * significa que não guarda a sessão do usuário no Servidor. */

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.csrf().disable().authorizeRequests()
                .antMatchers(HttpMethod.POST, "/login").permitAll()
                .anyRequest().authenticated()
                .and()
                .addFilter(new JWTAutenticarFilter(authenticationManager()))
                .addFilter(new JWTValidarFilter(authenticationManager()))
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
    }

    /*Criando configuração para o Cors.
    * O Cors permite que sua aplicação receba requisições de outros dominios,
    *  que não é o dominio dela.*/
    @Bean
    CorsConfigurationSource corsConfigurationSource(){

        final UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        CorsConfiguration corsConfiguration = new CorsConfiguration().applyPermitDefaultValues();
        source.registerCorsConfiguration("/**", corsConfiguration);
        return source;
    }
}
