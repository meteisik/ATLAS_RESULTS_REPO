import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P03_V2_JadeGlint {
    private static final int PRIVATE_STATIC_FINAL_FIVE = 5;

    private void applyJadeGlintDeletion(String data, boolean authorized) throws SQLException {
        Connection jadeGlintConnection = DriverManager.getConnection("jdbc:hsqldb:mem:jadeGlint");
        try {
            PreparedStatement jadeGlintDelete = jadeGlintConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            jadeGlintDelete.setString(1, data);
            if (authorized) {
                jadeGlintDelete.executeUpdate();
            }
        } finally {
            jadeGlintConnection.close();
        }
    }

    public void deleteJadeGlintAccount() throws SQLException {
        String data;
        if (PRIVATE_STATIC_FINAL_FIVE == 5) {
            data = System.getenv("JADE_GLINT_ACCOUNT_ID");
        } else {
            data = null;
        }
        String requester = System.getProperty("user.name");
        boolean authorized = isAuthorized(requester);
        applyJadeGlintDeletion(data, authorized);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
