import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P12_V1_VelvetCascadeSafe {

    public void deleteVelvetCascadeAccount() throws SQLException {
        String data;
        data = System.getenv("VELVET_CASCADE_ACCOUNT_ID");
        boolean authorized = isAuthorized(data);
        CWE284_P12_V1_VelvetCascadeSafeBase baseObject = new CWE284_P12_V1_VelvetCascadeSafeRemover();
        baseObject.action(data, authorized);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

abstract class CWE284_P12_V1_VelvetCascadeSafeBase {
    public abstract void action(String data, boolean authorized) throws SQLException;
}

class CWE284_P12_V1_VelvetCascadeSafeRemover extends CWE284_P12_V1_VelvetCascadeSafeBase {
    public void action(String data, boolean authorized) throws SQLException {
        Connection velvetCascadeConnection = DriverManager.getConnection("jdbc:hsqldb:mem:velvetCascade");
        try {
            PreparedStatement velvetCascadeDelete = velvetCascadeConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            velvetCascadeDelete.setString(1, data);
            if (!authorized) {
                System.err.println("delete of account " + data + " refused");
            } else {
                velvetCascadeDelete.executeUpdate();
            }
        } finally {
            velvetCascadeConnection.close();
        }
    }
}
