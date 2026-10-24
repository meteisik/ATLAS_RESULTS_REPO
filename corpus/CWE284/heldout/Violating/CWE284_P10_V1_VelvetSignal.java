import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P10_V1_VelvetSignal {

    public static String data;

    public static boolean authorized;

    public void deleteVelvetSignalAccount() throws SQLException {
        data = System.getenv("VELVET_SIGNAL_ACCOUNT_ID");
        authorized = isAuthorized(data);
        (new CWE284_P10_V1_VelvetSignalSink()).applyVelvetSignalDeletion();
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P10_V1_VelvetSignalSink {
    public void applyVelvetSignalDeletion() throws SQLException {
        String data = CWE284_P10_V1_VelvetSignal.data;
        boolean authorized = CWE284_P10_V1_VelvetSignal.authorized;
        Connection velvetSignalConnection = DriverManager.getConnection("jdbc:hsqldb:mem:velvetSignal");
        try {
            PreparedStatement velvetSignalDelete = velvetSignalConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            velvetSignalDelete.setString(1, data);
            velvetSignalDelete.executeUpdate();
            if (!authorized) {
                throw new SecurityException("delete of account " + data + " is not authorized");
            }
        } finally {
            velvetSignalConnection.close();
        }
    }
}
