import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P07_V2_VelvetSignalSafe {
    private static int privateFive = 5;

    public void deleteVelvetSignalAccount() throws SQLException {
        String data;
        if (privateFive == 5) {
            data = System.getenv("VELVET_SIGNAL_ACCOUNT_ID");
        } else {
            data = null;
        }
        String requester = System.getProperty("user.name");
        boolean authorized = (new CWE284_P07_V2_VelvetSignalSafeChecker()).isAuthorized(data);
        Connection velvetSignalConnection = DriverManager.getConnection("jdbc:hsqldb:mem:velvetSignal");
        try {
            PreparedStatement velvetSignalDelete = velvetSignalConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            velvetSignalDelete.setString(1, data);
            if (authorized) {
                velvetSignalDelete.executeUpdate();
            }
        } finally {
            velvetSignalConnection.close();
        }
    }
}

class CWE284_P07_V2_VelvetSignalSafeChecker {
    public boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        boolean authorized = operator != null && operator.equals(accountId);
        return authorized;
    }
}
