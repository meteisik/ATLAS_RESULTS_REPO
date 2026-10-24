import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P12_V1_VividSundialSafe {

    public void deleteVividSundialAccount() throws SQLException {
        String data;
        data = System.getenv("VIVID_SUNDIAL_ACCOUNT_ID");
        boolean authorized = isAuthorized(data);
        CWE284_P12_V1_VividSundialSafeBase baseObject = new CWE284_P12_V1_VividSundialSafeRemover();
        baseObject.action(data, authorized);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

abstract class CWE284_P12_V1_VividSundialSafeBase {
    public abstract void action(String data, boolean authorized) throws SQLException;
}

class CWE284_P12_V1_VividSundialSafeRemover extends CWE284_P12_V1_VividSundialSafeBase {
    public void action(String data, boolean authorized) throws SQLException {
        Connection vividSundialConnection = DriverManager.getConnection("jdbc:hsqldb:mem:vividSundial");
        try {
            PreparedStatement vividSundialDelete = vividSundialConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            vividSundialDelete.setString(1, data);
            if (!authorized) {
                System.err.println("delete of account " + data + " refused");
            } else {
                vividSundialDelete.executeUpdate();
            }
        } finally {
            vividSundialConnection.close();
        }
    }
}
