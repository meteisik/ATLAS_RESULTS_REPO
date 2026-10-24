import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P06_V1_JadeGlint {

    public void deleteJadeGlintAccount() throws SQLException {
        String data;
        data = System.getenv("JADE_GLINT_ACCOUNT_ID");
        boolean authorized = isAuthorized(data);
        (new CWE284_P06_V1_JadeGlintSink()).applyJadeGlintDeletion(data, authorized);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P06_V1_JadeGlintSink {
    public void applyJadeGlintDeletion(String data, boolean authorized) throws SQLException {
        Connection jadeGlintConnection = DriverManager.getConnection("jdbc:hsqldb:mem:jadeGlint");
        try {
            PreparedStatement jadeGlintDelete = jadeGlintConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            jadeGlintDelete.setString(1, data);
            jadeGlintDelete.executeUpdate();
            if (!authorized) {
                throw new SecurityException("delete of account " + data + " is not authorized");
            }
        } finally {
            jadeGlintConnection.close();
        }
    }
}
