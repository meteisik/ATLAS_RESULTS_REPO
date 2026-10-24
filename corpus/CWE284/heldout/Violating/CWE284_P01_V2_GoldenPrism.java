import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P01_V2_GoldenPrism {

    public void deleteGoldenPrismAccount() throws SQLException {
        String data;
        switch (7) {
        case 7:
            data = System.getenv("GOLDEN_PRISM_ACCOUNT_ID");
            break;
        default:
            data = null;
            break;
        }
        boolean authorized = isAuthorized(data);
        Connection goldenPrismConnection = DriverManager.getConnection("jdbc:hsqldb:mem:goldenPrism");
        try {
            PreparedStatement goldenPrismDelete = goldenPrismConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            goldenPrismDelete.setString(1, data);
            goldenPrismDelete.executeUpdate();
        } finally {
            goldenPrismConnection.close();
        }
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
