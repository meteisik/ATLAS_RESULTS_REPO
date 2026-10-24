import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P12_V1_AmberCipherSafe {

    public void deleteAmberCipherAccount() throws SQLException {
        String data;
        data = System.getenv("AMBER_CIPHER_ACCOUNT_ID");
        boolean authorized = isAuthorized(data);
        CWE284_P12_V1_AmberCipherSafeBase baseObject = new CWE284_P12_V1_AmberCipherSafeRemover();
        baseObject.action(data, authorized);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

abstract class CWE284_P12_V1_AmberCipherSafeBase {
    public abstract void action(String data, boolean authorized) throws SQLException;
}

class CWE284_P12_V1_AmberCipherSafeRemover extends CWE284_P12_V1_AmberCipherSafeBase {
    public void action(String data, boolean authorized) throws SQLException {
        Connection amberCipherConnection = DriverManager.getConnection("jdbc:hsqldb:mem:amberCipher");
        try {
            PreparedStatement amberCipherDelete = amberCipherConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            amberCipherDelete.setString(1, data);
            if (!authorized) {
                System.err.println("delete of account " + data + " refused");
            } else {
                amberCipherDelete.executeUpdate();
            }
        } finally {
            amberCipherConnection.close();
        }
    }
}
