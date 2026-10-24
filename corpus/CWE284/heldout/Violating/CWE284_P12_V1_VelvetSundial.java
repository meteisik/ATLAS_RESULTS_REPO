import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P12_V1_VelvetSundial {

    public void deleteVelvetSundialAccount() throws SQLException {
        String data;
        data = System.getenv("VELVET_SUNDIAL_ACCOUNT_ID");
        boolean authorized = isAuthorized(data);
        CWE284_P12_V1_VelvetSundialBase baseObject = new CWE284_P12_V1_VelvetSundialRemover();
        baseObject.action(data, authorized);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

abstract class CWE284_P12_V1_VelvetSundialBase {
    public abstract void action(String data, boolean authorized) throws SQLException;
}

class CWE284_P12_V1_VelvetSundialRemover extends CWE284_P12_V1_VelvetSundialBase {
    public void action(String data, boolean authorized) throws SQLException {
        Connection velvetSundialConnection = DriverManager.getConnection("jdbc:hsqldb:mem:velvetSundial");
        try {
            PreparedStatement velvetSundialDelete = velvetSundialConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            velvetSundialDelete.setString(1, data);
            if (authorized) {
                System.err.println("delete of account " + data + " refused");
            } else {
                velvetSundialDelete.executeUpdate();
            }
        } finally {
            velvetSundialConnection.close();
        }
    }
}
