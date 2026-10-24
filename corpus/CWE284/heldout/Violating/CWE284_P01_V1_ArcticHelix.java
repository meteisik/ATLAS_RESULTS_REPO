import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P01_V1_ArcticHelix {

    public void deleteArcticHelixAccount() throws SQLException {
        String data;
        data = System.getenv("ARCTIC_HELIX_ACCOUNT_ID");
        boolean authorized = isAuthorized(data);
        Connection arcticHelixConnection = DriverManager.getConnection("jdbc:hsqldb:mem:arcticHelix");
        try {
            PreparedStatement arcticHelixDelete = arcticHelixConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            arcticHelixDelete.setString(1, data);
            arcticHelixDelete.executeUpdate();
        } finally {
            arcticHelixConnection.close();
        }
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
