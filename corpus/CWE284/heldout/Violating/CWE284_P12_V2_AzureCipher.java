import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P12_V2_AzureCipher {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    public void deleteAzureCipherAccount() throws SQLException {
        String data;
        if (IO.staticTrue) {
            data = System.getenv("AZURE_CIPHER_ACCOUNT_ID");
        } else {
            data = null;
        }
        boolean authorized = isAuthorized(data);
        CWE284_P12_V2_AzureCipherBase baseObject = new CWE284_P12_V2_AzureCipherRemover();
        baseObject.action(data, authorized);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

abstract class CWE284_P12_V2_AzureCipherBase {
    public abstract void action(String data, boolean authorized) throws SQLException;
}

class CWE284_P12_V2_AzureCipherRemover extends CWE284_P12_V2_AzureCipherBase {
    public void action(String data, boolean authorized) throws SQLException {
        Connection azureCipherConnection = DriverManager.getConnection("jdbc:hsqldb:mem:azureCipher");
        try {
            PreparedStatement azureCipherDelete = azureCipherConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            azureCipherDelete.setString(1, data);
            if (authorized) {
                System.err.println("delete of account " + data + " refused");
            } else {
                azureCipherDelete.executeUpdate();
            }
        } finally {
            azureCipherConnection.close();
        }
    }
}
