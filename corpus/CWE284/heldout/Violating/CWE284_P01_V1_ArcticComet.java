import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P01_V1_ArcticComet {

    public void deleteArcticCometAccount() throws SQLException {
        String data;
        data = System.getenv("ARCTIC_COMET_ACCOUNT_ID");
        boolean authorized = isAuthorized(data);
        Connection arcticCometConnection = DriverManager.getConnection("jdbc:hsqldb:mem:arcticComet");
        try {
            PreparedStatement arcticCometDelete = arcticCometConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            arcticCometDelete.setString(1, data);
            arcticCometDelete.executeUpdate();
        } finally {
            arcticCometConnection.close();
        }
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
