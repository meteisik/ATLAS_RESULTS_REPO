import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P06_V1_NovaGlintSafe {

    public void deleteNovaGlintAccount() throws SQLException {
        String data;
        data = System.getenv("NOVA_GLINT_ACCOUNT_ID");
        boolean authorized = isAuthorized(data);
        (new CWE284_P06_V1_NovaGlintSafeSink()).applyNovaGlintDeletion(data, authorized);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P06_V1_NovaGlintSafeSink {
    public void applyNovaGlintDeletion(String data, boolean authorized) throws SQLException {
        Connection novaGlintConnection = DriverManager.getConnection("jdbc:hsqldb:mem:novaGlint");
        try {
            PreparedStatement novaGlintDelete = novaGlintConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            novaGlintDelete.setString(1, data);
            if (authorized) {
                novaGlintDelete.executeUpdate();
            } else {
                throw new SecurityException("delete of account " + data + " is not authorized");
            }
        } finally {
            novaGlintConnection.close();
        }
    }
}
