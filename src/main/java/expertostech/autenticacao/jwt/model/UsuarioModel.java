package expertostech.autenticacao.jwt.model;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import javax.persistence.*;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Entity(name="Usuario")
public class UsuarioModel {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Integer id;
    @Column(unique = true)
    private String login;

    /*O JsonProperty.Access.WRITE_ONLY é para não exibir o password ao listar os dados
    * no Postman */
    @JsonProperty(access = JsonProperty.Access.WRITE_ONLY)
    private String password;

}
