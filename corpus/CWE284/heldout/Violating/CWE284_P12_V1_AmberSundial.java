import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P12_V1_AmberSundial {

    public void deleteAmberSundialAccount() throws SQLException {
        String data;
        data = System.getenv("AMBER_SUNDIAL_ACCOUNT_ID");
        boolean authorized = isAuthorized(data);
        CWE284_P12_V1_AmberSundialBase baseObject = new CWE284_P12_V1_AmberSundialRemover();
        baseObject.action(data, authorized);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

abstract class CWE284_P12_V1_AmberSundialBase {
    public abstract void action(String data, boolean authorized) throws SQLException;
}

class CWE284_P12_V1_AmberSundialRemover extends CWE284_P12_V1_AmberSundialBase {
    public void action(String data, boolean authorized) throws SQLException {
        Connection amberSundialConnection = DriverManager.getConnection("jdbc:hsqldb:mem:amberSundial");
        try {
            PreparedStatement amberSundialDelete = amberSundialConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            amberSundialDelete.setString(1, data);
            if (authorized) {
                System.err.println("delete of account " + data + " refused");
            } else {
                amberSundialDelete.executeUpdate();
            }
        } finally {
            amberSundialConnection.close();
        }
    }
}
