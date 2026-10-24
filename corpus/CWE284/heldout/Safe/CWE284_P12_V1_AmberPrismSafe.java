import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P12_V1_AmberPrismSafe {

    public void deleteAmberPrismAccount() throws SQLException {
        String data;
        data = System.getenv("AMBER_PRISM_ACCOUNT_ID");
        boolean authorized = isAuthorized(data);
        CWE284_P12_V1_AmberPrismSafeBase baseObject = new CWE284_P12_V1_AmberPrismSafeRemover();
        baseObject.action(data, authorized);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

abstract class CWE284_P12_V1_AmberPrismSafeBase {
    public abstract void action(String data, boolean authorized) throws SQLException;
}

class CWE284_P12_V1_AmberPrismSafeRemover extends CWE284_P12_V1_AmberPrismSafeBase {
    public void action(String data, boolean authorized) throws SQLException {
        Connection amberPrismConnection = DriverManager.getConnection("jdbc:hsqldb:mem:amberPrism");
        try {
            PreparedStatement amberPrismDelete = amberPrismConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            amberPrismDelete.setString(1, data);
            if (!authorized) {
                System.err.println("delete of account " + data + " refused");
            } else {
                amberPrismDelete.executeUpdate();
            }
        } finally {
            amberPrismConnection.close();
        }
    }
}
