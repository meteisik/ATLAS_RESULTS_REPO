import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P12_V1_VelvetFlareSafe {

    public void deleteVelvetFlareAccount() throws SQLException {
        String data;
        data = System.getenv("VELVET_FLARE_ACCOUNT_ID");
        boolean authorized = isAuthorized(data);
        CWE284_P12_V1_VelvetFlareSafeBase baseObject = new CWE284_P12_V1_VelvetFlareSafeRemover();
        baseObject.action(data, authorized);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

abstract class CWE284_P12_V1_VelvetFlareSafeBase {
    public abstract void action(String data, boolean authorized) throws SQLException;
}

class CWE284_P12_V1_VelvetFlareSafeRemover extends CWE284_P12_V1_VelvetFlareSafeBase {
    public void action(String data, boolean authorized) throws SQLException {
        Connection velvetFlareConnection = DriverManager.getConnection("jdbc:hsqldb:mem:velvetFlare");
        try {
            PreparedStatement velvetFlareDelete = velvetFlareConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            velvetFlareDelete.setString(1, data);
            if (!authorized) {
                System.err.println("delete of account " + data + " refused");
            } else {
                velvetFlareDelete.executeUpdate();
            }
        } finally {
            velvetFlareConnection.close();
        }
    }
}
