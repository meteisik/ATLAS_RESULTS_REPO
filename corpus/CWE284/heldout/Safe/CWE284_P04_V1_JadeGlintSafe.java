import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P04_V1_JadeGlintSafe {

    private boolean checkJadeGlintAccess(String accountId) {
        boolean authorized = isAuthorized(accountId);
        return authorized;
    }

    public void deleteJadeGlintAccount() throws SQLException {
        String data;
        data = System.getenv("JADE_GLINT_ACCOUNT_ID");
        boolean authorized = checkJadeGlintAccess(data);
        Connection jadeGlintConnection = DriverManager.getConnection("jdbc:hsqldb:mem:jadeGlint");
        try {
            PreparedStatement jadeGlintDelete = jadeGlintConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            jadeGlintDelete.setString(1, data);
            if (!authorized) {
                System.err.println("delete of account " + data + " refused");
            } else {
                jadeGlintDelete.executeUpdate();
            }
        } finally {
            jadeGlintConnection.close();
        }
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
