import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P12_V2_AzureSundialSafe {

    public void deleteAzureSundialAccount() throws SQLException {
        String data;
        if (true) {
            data = System.getenv("AZURE_SUNDIAL_ACCOUNT_ID");
        } else {
            data = null;
        }
        boolean authorized = isAuthorized(data);
        CWE284_P12_V2_AzureSundialSafeBase baseObject = new CWE284_P12_V2_AzureSundialSafeRemover();
        baseObject.action(data, authorized);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

abstract class CWE284_P12_V2_AzureSundialSafeBase {
    public abstract void action(String data, boolean authorized) throws SQLException;
}

class CWE284_P12_V2_AzureSundialSafeRemover extends CWE284_P12_V2_AzureSundialSafeBase {
    public void action(String data, boolean authorized) throws SQLException {
        Connection azureSundialConnection = DriverManager.getConnection("jdbc:hsqldb:mem:azureSundial");
        try {
            PreparedStatement azureSundialDelete = azureSundialConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            azureSundialDelete.setString(1, data);
            if (!authorized) {
                System.err.println("delete of account " + data + " refused");
            } else {
                azureSundialDelete.executeUpdate();
            }
        } finally {
            azureSundialConnection.close();
        }
    }
}
