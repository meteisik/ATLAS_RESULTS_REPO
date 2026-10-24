import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P05_V1_GoldenSignalSafe {

    private String goldenSignalAccountId;

    private boolean goldenSignalAuthorized;

    private void applyGoldenSignalDeletion() throws SQLException {
        String data = goldenSignalAccountId;
        boolean authorized = goldenSignalAuthorized;
        Connection goldenSignalConnection = DriverManager.getConnection("jdbc:hsqldb:mem:goldenSignal");
        try {
            PreparedStatement goldenSignalDelete = goldenSignalConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            goldenSignalDelete.setString(1, data);
            if (authorized) {
                goldenSignalDelete.executeUpdate();
            }
        } finally {
            goldenSignalConnection.close();
        }
    }

    public void deleteGoldenSignalAccount() throws SQLException {
        String data;
        data = System.getenv("GOLDEN_SIGNAL_ACCOUNT_ID");
        goldenSignalAccountId = data;
        goldenSignalAuthorized = isAuthorized(data);
        applyGoldenSignalDeletion();
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
