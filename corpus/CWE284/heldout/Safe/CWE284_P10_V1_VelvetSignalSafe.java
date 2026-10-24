import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P10_V1_VelvetSignalSafe {

    public static String data;

    public static boolean authorized;

    public void deleteVelvetSignalAccount() throws SQLException {
        data = System.getenv("VELVET_SIGNAL_ACCOUNT_ID");
        authorized = isAuthorized(data);
        (new CWE284_P10_V1_VelvetSignalSafeSink()).applyVelvetSignalDeletion();
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P10_V1_VelvetSignalSafeSink {
    public void applyVelvetSignalDeletion() throws SQLException {
        String data = CWE284_P10_V1_VelvetSignalSafe.data;
        boolean authorized = CWE284_P10_V1_VelvetSignalSafe.authorized;
        Connection velvetSignalConnection = DriverManager.getConnection("jdbc:hsqldb:mem:velvetSignal");
        try {
            PreparedStatement velvetSignalDelete = velvetSignalConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            velvetSignalDelete.setString(1, data);
            if (authorized) {
                velvetSignalDelete.executeUpdate();
            } else {
                throw new SecurityException("delete of account " + data + " is not authorized");
            }
        } finally {
            velvetSignalConnection.close();
        }
    }
}
