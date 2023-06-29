package expertostech.autenticacao.jwt.security;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.fasterxml.jackson.databind.ObjectMapper;
import expertostech.autenticacao.jwt.data.DetalheUsuarioData;
import expertostech.autenticacao.jwt.model.UsuarioModel;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Date;


public class JWTAutenticarFilter extends UsernamePasswordAuthenticationFilter {

    //A classe JWTAutenticarFilter nesse código é para criar o token

    //Exibir os logs no console
    Logger logger = LogManager.getLogger(JWTAutenticarFilter.class);
    public static final int TOKEN_EXPIRATION = 600_000;
    //Essa senha seria bom colocar em um arquivo de configuração só está aqui por teste de estudo
    public static final String  TOKEN_SECRET = "98a854dd-fbb3-4d8d-9e48-1ca78a3bce9a";
    private final AuthenticationManager authenticationManager;

    public JWTAutenticarFilter(AuthenticationManager authenticationManager) {
        this.authenticationManager = authenticationManager;
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request,
                                                HttpServletResponse response) throws AuthenticationException {
       //Realiza o tratamento da autenticacao
        /*O objectMapper serve para retornar o UsuarioModel no formato JSON.
        O objectMapper vem do jackson que é um componente de manipulação de JSON */
        try {
            UsuarioModel usuario = new ObjectMapper().readValue(request.getInputStream(), UsuarioModel.class);

            /*O AuthenticationManager retornar alguns dados entre eles login, senha e permissoes.
            * No exemplo abaixo não tera permissões por isso retorna um Array vazio*/
            return authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(
                    usuario.getLogin(),
                    usuario.getPassword(),
                    new ArrayList<>()
            ));
        } catch (IOException e) {
            throw new RuntimeException("Falha ao autenticar usuario", e);
        }
    }

    /*Caso ocorra um sucesso na autenticacao*/

    @Override
    protected void successfulAuthentication(HttpServletRequest request,
                                            HttpServletResponse response,
                                            FilterChain chain,
                                            Authentication authResult)
            throws IOException, ServletException {

        DetalheUsuarioData usuarioData = (DetalheUsuarioData) authResult.getPrincipal();

        logger.info("Iniciando a geração do Token!");

        /*Para criar o token é necessário colocar a dependencia do auth0 no POM*/
        //Gera o token passando o username, segundos para expirar e senha GUID
        String token = JWT.create()
                .withSubject(usuarioData.getUsername())
                .withExpiresAt(new Date(System.currentTimeMillis() + TOKEN_EXPIRATION))
                .sign(Algorithm.HMAC512(TOKEN_SECRET));

         logger.info("Token gerado -> " + token);
        //Registra o token no corpo da página
        response.getWriter().write(token);
        response.getWriter().flush();
    }
}
