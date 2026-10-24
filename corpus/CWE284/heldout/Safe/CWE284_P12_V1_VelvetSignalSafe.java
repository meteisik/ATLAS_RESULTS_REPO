import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P12_V1_VelvetSignalSafe {

    public void deleteVelvetSignalAccount() throws SQLException {
        String data;
        data = System.getenv("VELVET_SIGNAL_ACCOUNT_ID");
        boolean authorized = isAuthorized(data);
        CWE284_P12_V1_VelvetSignalSafeBase baseObject = new CWE284_P12_V1_VelvetSignalSafeRemover();
        baseObject.action(data, authorized);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

abstract class CWE284_P12_V1_VelvetSignalSafeBase {
    public abstract void action(String data, boolean authorized) throws SQLException;
}

class CWE284_P12_V1_VelvetSignalSafeRemover extends CWE284_P12_V1_VelvetSignalSafeBase {
    public void action(String data, boolean authorized) throws SQLException {
        Connection velvetSignalConnection = DriverManager.getConnection("jdbc:hsqldb:mem:velvetSignal");
        try {
            PreparedStatement velvetSignalDelete = velvetSignalConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            velvetSignalDelete.setString(1, data);
            if (!authorized) {
                System.err.println("delete of account " + data + " refused");
            } else {
                velvetSignalDelete.executeUpdate();
            }
        } finally {
            velvetSignalConnection.close();
        }
    }
}
