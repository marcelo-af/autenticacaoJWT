package expertostech.autenticacao.jwt.security;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;

public class JWTValidarFilter extends BasicAuthenticationFilter {

    //A classe JWTValidarFilter nesse código é para ver se o token está correto

    //Exibir os logs
    Logger logger = LogManager.getLogger(JWTValidarFilter.class);
    public static final String ATRIBUTO_DO_HEADER = "Authorization";
    public static final String PREFIXO_DO_HEADER =  "Bearer ";
    public JWTValidarFilter(AuthenticationManager authenticationManager) {
        super(authenticationManager);
    }

    /* O metodo doFilterInternal é sobreescrito para verifica o cabeçalho*/

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain chain) throws IOException, ServletException {

        String atributoCabecalho = request.getHeader(ATRIBUTO_DO_HEADER);

        //Procura no cabeçalho/header o atributo Authorization
        if(atributoCabecalho == null) {
            chain.doFilter(request, response);
            return;
        }

        //Verifica se o prefixo do cabeçalho/header começa com Bearer
        if(!atributoCabecalho.startsWith(PREFIXO_DO_HEADER)){
            chain.doFilter(request, response);
            return;
        }

        //Remove o PREFIXO_DO_HEADER do Token
        String token = atributoCabecalho.replace(PREFIXO_DO_HEADER, "");

        //metodo getAuthenticationToken irá fazer a leitura do token
        UsernamePasswordAuthenticationToken authenticationToken = getAuthenticationToken(token);

        SecurityContextHolder.getContext().setAuthentication(authenticationToken);
        chain.doFilter(request, response);

    }

    /*O metodo getAuthenticationToken faz a leitura do token e retorna os dados do
    usuario para garantir que é um usuário válido*/
    private UsernamePasswordAuthenticationToken getAuthenticationToken(String token){

        logger.info("Iniciando a verificação do Token.");

        /* Retira o nome do usuário.
         O .build() é para criar a leitura.
         O .verify() é para verificar o conteúdo do Token.
         O .getSubject() é onde colocou o nome do usuário */
        String usuario = JWT.require(Algorithm.HMAC512(JWTAutenticarFilter.TOKEN_SECRET))
                .build()
                .verify(token)
                .getSubject();

        if(usuario == null){
            return null;
        }

        logger.info("Token validado com sucesso :) ");
        /*Retorna o usuario, senha(null) e lista de permissões(lista vazia)*/
        return new UsernamePasswordAuthenticationToken(usuario, null, new ArrayList<>());

    }
}
