import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P04_V1_GoldenSignalSafe {

    private boolean checkGoldenSignalAccess(String accountId) {
        boolean authorized = isAuthorized(accountId);
        return authorized;
    }

    public void deleteGoldenSignalAccount() throws SQLException {
        String data;
        data = System.getenv("GOLDEN_SIGNAL_ACCOUNT_ID");
        boolean authorized = checkGoldenSignalAccess(data);
        Connection goldenSignalConnection = DriverManager.getConnection("jdbc:hsqldb:mem:goldenSignal");
        try {
            PreparedStatement goldenSignalDelete = goldenSignalConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            goldenSignalDelete.setString(1, data);
            if (!authorized) {
                System.err.println("delete of account " + data + " refused");
            } else {
                goldenSignalDelete.executeUpdate();
            }
        } finally {
            goldenSignalConnection.close();
        }
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
