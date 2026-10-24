import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P01_V2_GoldenSignal {

    public void deleteGoldenSignalAccount() throws SQLException {
        String data;
        data = null;
        for (int j = 0; j < 1; j++) {
            data = System.getenv("GOLDEN_SIGNAL_ACCOUNT_ID");
        }
        boolean authorized = isAuthorized(data);
        Connection goldenSignalConnection = DriverManager.getConnection("jdbc:hsqldb:mem:goldenSignal");
        try {
            PreparedStatement goldenSignalDelete = goldenSignalConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            goldenSignalDelete.setString(1, data);
            goldenSignalDelete.executeUpdate();
        } finally {
            goldenSignalConnection.close();
        }
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
