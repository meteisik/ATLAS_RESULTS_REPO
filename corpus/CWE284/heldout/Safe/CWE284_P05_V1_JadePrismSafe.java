import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P05_V1_JadePrismSafe {

    private String jadePrismAccountId;

    private boolean jadePrismAuthorized;

    private void applyJadePrismDeletion() throws SQLException {
        String data = jadePrismAccountId;
        boolean authorized = jadePrismAuthorized;
        Connection jadePrismConnection = DriverManager.getConnection("jdbc:hsqldb:mem:jadePrism");
        try {
            PreparedStatement jadePrismDelete = jadePrismConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            jadePrismDelete.setString(1, data);
            if (authorized) {
                jadePrismDelete.executeUpdate();
            }
        } finally {
            jadePrismConnection.close();
        }
    }

    public void deleteJadePrismAccount() throws SQLException {
        String data;
        data = System.getenv("JADE_PRISM_ACCOUNT_ID");
        jadePrismAccountId = data;
        jadePrismAuthorized = isAuthorized(data);
        applyJadePrismDeletion();
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
