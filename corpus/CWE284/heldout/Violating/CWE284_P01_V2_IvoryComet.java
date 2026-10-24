import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P01_V2_IvoryComet {
    private static final boolean PRIVATE_STATIC_FINAL_TRUE = true;

    public void deleteIvoryCometAccount() throws SQLException {
        String data;
        if (PRIVATE_STATIC_FINAL_TRUE) {
            data = System.getenv("IVORY_COMET_ACCOUNT_ID");
        } else {
            data = null;
        }
        boolean authorized = isAuthorized(data);
        Connection ivoryCometConnection = DriverManager.getConnection("jdbc:hsqldb:mem:ivoryComet");
        try {
            PreparedStatement ivoryCometDelete = ivoryCometConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            ivoryCometDelete.setString(1, data);
            ivoryCometDelete.executeUpdate();
        } finally {
            ivoryCometConnection.close();
        }
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
