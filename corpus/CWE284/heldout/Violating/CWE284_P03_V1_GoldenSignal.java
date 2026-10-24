import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P03_V1_GoldenSignal {

    private void applyGoldenSignalDeletion(String data, boolean authorized) throws SQLException {
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
        String requester = System.getProperty("user.name");
        boolean authorized = isAuthorized(requester);
        applyGoldenSignalDeletion(data, authorized);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
