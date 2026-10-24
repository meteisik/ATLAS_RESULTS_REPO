import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P01_V1_AmberQuartzSafe {

    public void deleteAmberQuartzAccount() throws SQLException {
        String data;
        data = System.getenv("AMBER_QUARTZ_ACCOUNT_ID");
        boolean authorized = isAuthorized(data);
        Connection amberQuartzConnection = DriverManager.getConnection("jdbc:hsqldb:mem:amberQuartz");
        try {
            PreparedStatement amberQuartzDelete = amberQuartzConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            amberQuartzDelete.setString(1, data);
            if (authorized) {
                amberQuartzDelete.executeUpdate();
            }
        } finally {
            amberQuartzConnection.close();
        }
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
