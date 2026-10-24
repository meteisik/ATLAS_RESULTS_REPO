import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P12_V2_CobaltKestrel {

    public void deleteCobaltKestrelAccount() throws SQLException {
        String data;
        if (5 == 5) {
            data = System.getenv("COBALT_KESTREL_ACCOUNT_ID");
        } else {
            data = null;
        }
        boolean authorized = isAuthorized(data);
        CWE284_P12_V2_CobaltKestrelBase baseObject = new CWE284_P12_V2_CobaltKestrelRemover();
        baseObject.action(data, authorized);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

abstract class CWE284_P12_V2_CobaltKestrelBase {
    public abstract void action(String data, boolean authorized) throws SQLException;
}

class CWE284_P12_V2_CobaltKestrelRemover extends CWE284_P12_V2_CobaltKestrelBase {
    public void action(String data, boolean authorized) throws SQLException {
        Connection cobaltKestrelConnection = DriverManager.getConnection("jdbc:hsqldb:mem:cobaltKestrel");
        try {
            PreparedStatement cobaltKestrelDelete = cobaltKestrelConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            cobaltKestrelDelete.setString(1, data);
            if (authorized) {
                System.err.println("delete of account " + data + " refused");
            } else {
                cobaltKestrelDelete.executeUpdate();
            }
        } finally {
            cobaltKestrelConnection.close();
        }
    }
}
