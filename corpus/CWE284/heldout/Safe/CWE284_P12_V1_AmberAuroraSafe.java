import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P12_V1_AmberAuroraSafe {

    public void deleteAmberAuroraAccount() throws SQLException {
        String data;
        data = System.getenv("AMBER_AURORA_ACCOUNT_ID");
        boolean authorized = isAuthorized(data);
        CWE284_P12_V1_AmberAuroraSafeBase baseObject = new CWE284_P12_V1_AmberAuroraSafeRemover();
        baseObject.action(data, authorized);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

abstract class CWE284_P12_V1_AmberAuroraSafeBase {
    public abstract void action(String data, boolean authorized) throws SQLException;
}

class CWE284_P12_V1_AmberAuroraSafeRemover extends CWE284_P12_V1_AmberAuroraSafeBase {
    public void action(String data, boolean authorized) throws SQLException {
        Connection amberAuroraConnection = DriverManager.getConnection("jdbc:hsqldb:mem:amberAurora");
        try {
            PreparedStatement amberAuroraDelete = amberAuroraConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            amberAuroraDelete.setString(1, data);
            if (!authorized) {
                System.err.println("delete of account " + data + " refused");
            } else {
                amberAuroraDelete.executeUpdate();
            }
        } finally {
            amberAuroraConnection.close();
        }
    }
}
