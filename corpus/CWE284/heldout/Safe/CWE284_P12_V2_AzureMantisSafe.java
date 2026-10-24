import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P12_V2_AzureMantisSafe {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    public void deleteAzureMantisAccount() throws SQLException {
        String data;
        if (IO.staticFive == 5) {
            data = System.getenv("AZURE_MANTIS_ACCOUNT_ID");
        } else {
            data = null;
        }
        boolean authorized = isAuthorized(data);
        CWE284_P12_V2_AzureMantisSafeBase baseObject = new CWE284_P12_V2_AzureMantisSafeRemover();
        baseObject.action(data, authorized);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

abstract class CWE284_P12_V2_AzureMantisSafeBase {
    public abstract void action(String data, boolean authorized) throws SQLException;
}

class CWE284_P12_V2_AzureMantisSafeRemover extends CWE284_P12_V2_AzureMantisSafeBase {
    public void action(String data, boolean authorized) throws SQLException {
        Connection azureMantisConnection = DriverManager.getConnection("jdbc:hsqldb:mem:azureMantis");
        try {
            PreparedStatement azureMantisDelete = azureMantisConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            azureMantisDelete.setString(1, data);
            if (!authorized) {
                System.err.println("delete of account " + data + " refused");
            } else {
                azureMantisDelete.executeUpdate();
            }
        } finally {
            azureMantisConnection.close();
        }
    }
}
