import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P06_V1_MosaicKestrel {

    public void deleteMosaicKestrelAccount() throws SQLException {
        String data;
        data = System.getenv("MOSAIC_KESTREL_ACCOUNT_ID");
        boolean authorized = isAuthorized(data);
        (new CWE284_P06_V1_MosaicKestrelSink()).applyMosaicKestrelDeletion(data, authorized);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P06_V1_MosaicKestrelSink {
    public void applyMosaicKestrelDeletion(String data, boolean authorized) throws SQLException {
        Connection mosaicKestrelConnection = DriverManager.getConnection("jdbc:hsqldb:mem:mosaicKestrel");
        try {
            PreparedStatement mosaicKestrelDelete = mosaicKestrelConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            mosaicKestrelDelete.setString(1, data);
            mosaicKestrelDelete.executeUpdate();
            if (!authorized) {
                throw new SecurityException("delete of account " + data + " is not authorized");
            }
        } finally {
            mosaicKestrelConnection.close();
        }
    }
}
