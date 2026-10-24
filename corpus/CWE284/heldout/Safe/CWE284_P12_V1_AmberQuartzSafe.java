import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P12_V1_AmberQuartzSafe {

    public void deleteAmberQuartzAccount() throws SQLException {
        String data;
        data = System.getenv("AMBER_QUARTZ_ACCOUNT_ID");
        boolean authorized = isAuthorized(data);
        CWE284_P12_V1_AmberQuartzSafeBase baseObject = new CWE284_P12_V1_AmberQuartzSafeRemover();
        baseObject.action(data, authorized);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

abstract class CWE284_P12_V1_AmberQuartzSafeBase {
    public abstract void action(String data, boolean authorized) throws SQLException;
}

class CWE284_P12_V1_AmberQuartzSafeRemover extends CWE284_P12_V1_AmberQuartzSafeBase {
    public void action(String data, boolean authorized) throws SQLException {
        Connection amberQuartzConnection = DriverManager.getConnection("jdbc:hsqldb:mem:amberQuartz");
        try {
            PreparedStatement amberQuartzDelete = amberQuartzConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            amberQuartzDelete.setString(1, data);
            if (!authorized) {
                System.err.println("delete of account " + data + " refused");
            } else {
                amberQuartzDelete.executeUpdate();
            }
        } finally {
            amberQuartzConnection.close();
        }
    }
}
