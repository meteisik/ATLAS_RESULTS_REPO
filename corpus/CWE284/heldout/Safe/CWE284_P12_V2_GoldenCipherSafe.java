import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P12_V2_GoldenCipherSafe {
    private static boolean privateTrue = true;

    public void deleteGoldenCipherAccount() throws SQLException {
        String data;
        if (privateTrue) {
            data = System.getenv("GOLDEN_CIPHER_ACCOUNT_ID");
        } else {
            data = null;
        }
        boolean authorized = isAuthorized(data);
        CWE284_P12_V2_GoldenCipherSafeBase baseObject = new CWE284_P12_V2_GoldenCipherSafeRemover();
        baseObject.action(data, authorized);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

abstract class CWE284_P12_V2_GoldenCipherSafeBase {
    public abstract void action(String data, boolean authorized) throws SQLException;
}

class CWE284_P12_V2_GoldenCipherSafeRemover extends CWE284_P12_V2_GoldenCipherSafeBase {
    public void action(String data, boolean authorized) throws SQLException {
        Connection goldenCipherConnection = DriverManager.getConnection("jdbc:hsqldb:mem:goldenCipher");
        try {
            PreparedStatement goldenCipherDelete = goldenCipherConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            goldenCipherDelete.setString(1, data);
            if (!authorized) {
                System.err.println("delete of account " + data + " refused");
            } else {
                goldenCipherDelete.executeUpdate();
            }
        } finally {
            goldenCipherConnection.close();
        }
    }
}
