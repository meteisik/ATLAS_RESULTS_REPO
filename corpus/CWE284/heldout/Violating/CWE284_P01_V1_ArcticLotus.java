import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P01_V1_ArcticLotus {

    public void deleteArcticLotusAccount() throws SQLException {
        String data;
        data = System.getenv("ARCTIC_LOTUS_ACCOUNT_ID");
        boolean authorized = isAuthorized(data);
        Connection arcticLotusConnection = DriverManager.getConnection("jdbc:hsqldb:mem:arcticLotus");
        try {
            PreparedStatement arcticLotusDelete = arcticLotusConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            arcticLotusDelete.setString(1, data);
            arcticLotusDelete.executeUpdate();
        } finally {
            arcticLotusConnection.close();
        }
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
