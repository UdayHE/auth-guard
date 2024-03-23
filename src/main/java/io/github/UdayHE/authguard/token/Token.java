package io.github.UdayHE.authguard.token;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class Token {
  @Builder.Default
  public TokenType tokenType = TokenType.BEARER;
  private String token;
  private String username;
  private boolean expired;
  private boolean revoked;


}
