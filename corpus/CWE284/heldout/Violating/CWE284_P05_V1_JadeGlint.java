import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P05_V1_JadeGlint {

    private String jadeGlintAccountId;

    private boolean jadeGlintAuthorized;

    private void applyJadeGlintDeletion() throws SQLException {
        String data = jadeGlintAccountId;
        boolean authorized = jadeGlintAuthorized;
        Connection jadeGlintConnection = DriverManager.getConnection("jdbc:hsqldb:mem:jadeGlint");
        try {
            PreparedStatement jadeGlintDelete = jadeGlintConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            jadeGlintDelete.setString(1, data);
            jadeGlintDelete.executeUpdate();
        } finally {
            jadeGlintConnection.close();
        }
    }

    public void deleteJadeGlintAccount() throws SQLException {
        String data;
        data = System.getenv("JADE_GLINT_ACCOUNT_ID");
        jadeGlintAccountId = data;
        jadeGlintAuthorized = isAuthorized(data);
        applyJadeGlintDeletion();
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
