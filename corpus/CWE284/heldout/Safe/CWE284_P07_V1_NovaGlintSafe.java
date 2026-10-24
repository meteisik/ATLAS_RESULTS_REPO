import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P07_V1_NovaGlintSafe {

    public void deleteNovaGlintAccount() throws SQLException {
        String data;
        data = System.getenv("NOVA_GLINT_ACCOUNT_ID");
        String requester = System.getProperty("user.name");
        boolean authorized = (new CWE284_P07_V1_NovaGlintSafeChecker()).isAuthorized(data);
        Connection novaGlintConnection = DriverManager.getConnection("jdbc:hsqldb:mem:novaGlint");
        try {
            PreparedStatement novaGlintDelete = novaGlintConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            novaGlintDelete.setString(1, data);
            if (authorized) {
                novaGlintDelete.executeUpdate();
            }
        } finally {
            novaGlintConnection.close();
        }
    }
}

class CWE284_P07_V1_NovaGlintSafeChecker {
    public boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        boolean authorized = operator != null && operator.equals(accountId);
        return authorized;
    }
}
