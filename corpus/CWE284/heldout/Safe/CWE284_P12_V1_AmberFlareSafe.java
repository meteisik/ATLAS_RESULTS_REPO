import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P12_V1_AmberFlareSafe {

    public void deleteAmberFlareAccount() throws SQLException {
        String data;
        data = System.getenv("AMBER_FLARE_ACCOUNT_ID");
        boolean authorized = isAuthorized(data);
        CWE284_P12_V1_AmberFlareSafeBase baseObject = new CWE284_P12_V1_AmberFlareSafeRemover();
        baseObject.action(data, authorized);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

abstract class CWE284_P12_V1_AmberFlareSafeBase {
    public abstract void action(String data, boolean authorized) throws SQLException;
}

class CWE284_P12_V1_AmberFlareSafeRemover extends CWE284_P12_V1_AmberFlareSafeBase {
    public void action(String data, boolean authorized) throws SQLException {
        Connection amberFlareConnection = DriverManager.getConnection("jdbc:hsqldb:mem:amberFlare");
        try {
            PreparedStatement amberFlareDelete = amberFlareConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            amberFlareDelete.setString(1, data);
            if (!authorized) {
                System.err.println("delete of account " + data + " refused");
            } else {
                amberFlareDelete.executeUpdate();
            }
        } finally {
            amberFlareConnection.close();
        }
    }
}
