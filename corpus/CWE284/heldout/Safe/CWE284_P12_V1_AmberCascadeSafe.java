import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P12_V1_AmberCascadeSafe {

    public void deleteAmberCascadeAccount() throws SQLException {
        String data;
        data = System.getenv("AMBER_CASCADE_ACCOUNT_ID");
        boolean authorized = isAuthorized(data);
        CWE284_P12_V1_AmberCascadeSafeBase baseObject = new CWE284_P12_V1_AmberCascadeSafeRemover();
        baseObject.action(data, authorized);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

abstract class CWE284_P12_V1_AmberCascadeSafeBase {
    public abstract void action(String data, boolean authorized) throws SQLException;
}

class CWE284_P12_V1_AmberCascadeSafeRemover extends CWE284_P12_V1_AmberCascadeSafeBase {
    public void action(String data, boolean authorized) throws SQLException {
        Connection amberCascadeConnection = DriverManager.getConnection("jdbc:hsqldb:mem:amberCascade");
        try {
            PreparedStatement amberCascadeDelete = amberCascadeConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            amberCascadeDelete.setString(1, data);
            if (!authorized) {
                System.err.println("delete of account " + data + " refused");
            } else {
                amberCascadeDelete.executeUpdate();
            }
        } finally {
            amberCascadeConnection.close();
        }
    }
}
