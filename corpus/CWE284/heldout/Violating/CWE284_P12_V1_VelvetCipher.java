import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P12_V1_VelvetCipher {

    public void deleteVelvetCipherAccount() throws SQLException {
        String data;
        data = System.getenv("VELVET_CIPHER_ACCOUNT_ID");
        boolean authorized = isAuthorized(data);
        CWE284_P12_V1_VelvetCipherBase baseObject = new CWE284_P12_V1_VelvetCipherRemover();
        baseObject.action(data, authorized);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

abstract class CWE284_P12_V1_VelvetCipherBase {
    public abstract void action(String data, boolean authorized) throws SQLException;
}

class CWE284_P12_V1_VelvetCipherRemover extends CWE284_P12_V1_VelvetCipherBase {
    public void action(String data, boolean authorized) throws SQLException {
        Connection velvetCipherConnection = DriverManager.getConnection("jdbc:hsqldb:mem:velvetCipher");
        try {
            PreparedStatement velvetCipherDelete = velvetCipherConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            velvetCipherDelete.setString(1, data);
            if (authorized) {
                System.err.println("delete of account " + data + " refused");
            } else {
                velvetCipherDelete.executeUpdate();
            }
        } finally {
            velvetCipherConnection.close();
        }
    }
}
